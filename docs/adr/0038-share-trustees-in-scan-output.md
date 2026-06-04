# ADR 0038 — Share-DACL-Trustees im Scan-Output

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

Review 2026-06-04 Runde 3 Finding 3 (Medium): Der Scan-Pfad rief
`build_path_trustees(&fso, None, None)` auf — das **NTFS-only**-
Argument liess die Share-DACL ausserhalb der gesammelten
`path_trustees` und damit der pfadzentrischen Trustee-Tabelle.

Die HTML-Tabelle ist allerdings als **„who can access this path at
all"** beschriftet und besitzt sogar eine dedizierte
`TrusteeCategory::Share`-Spalte. Bei SMB-Analysen entstand dadurch
eine systematische Diskrepanz:

- **Risiko-Ansicht**: berücksichtigt korrekt Share ∩ NTFS, der
  effektive Befund kann "nur Read" sein, obwohl NTFS Modify gewährt.
- **Trustee-Ansicht** (gleicher Bericht): zeigt nur die NTFS-Allow-
  Einträge — Share-Deny, Share-Allow für breite Gruppen oder eine
  read-only Share-Maske bleiben unsichtbar.

Das verletzt die Memory-Regel „keine Silent Skips" (Stars-Berichte
müssen erklären, was sie zeigen und was sie verschweigen) sowie das
Audit-Versprechen „read-only Analyse erklärt vollständig".

## Entscheidung / Decision

**Share-DACL einmal pro Share lesen** und als Overlay an jeden Pfad
unter diesem Share anhängen:

1. **Neuer Typ `ShareTrusteeOverlay`** im GUI-Worker:

   ```rust
   pub struct ShareTrusteeOverlay {
       pub trustees: Vec<PathTrustee>,  // alle TrusteeCategory::Share
   }
   ```

2. **Neue Funktion `read_share_overlay(server, share)`** liest die
   Share-DACL via `get_share_dacl` einmal und produziert die
   `ShareTrusteeOverlay`. Lesefehler werden als sichtbare
   Pseudo-Zeile gerendert ("Share-DACL nicht lesbar: …") — keine
   stillen Skips.

3. **Neuer Helper `build_path_trustees_with_share(fso, overlay)`**
   nimmt eine schon gelesene Overlay-Referenz und vermeidet so den
   Re-Read pro Pfad. Die bestehende `build_path_trustees`-Signatur
   bleibt erhalten (für den Analyze-Einzelpfad-Use-Case).

4. **Scan-Pfad** (`handle_scan_path`) liest die Share-DACL **einmal**
   vor der Pfad-Schleife und übergibt die Overlay-Referenz an jeden
   `build_path_trustees_with_share`-Aufruf:

   ```rust
   let share_overlay = match (effective_smb_target(root, smb_server),
                              share_name.or_else(parse_unc)) {
       (Some(s), Some(n)) => Some(read_share_overlay(&s, &n)),
       _ => None,
   };
   for fso in walk.objects {
       let raw_trustees = build_path_trustees_with_share(&fso, share_overlay.as_ref());
       …
   }
   ```

Die Share-DACL ist eine Eigenschaft des Shares, nicht des Unterpfads
— ein einmaliger Read pro Scan ist sowohl semantisch korrekt als auch
performance-freundlich.

## Konsequenzen / Consequences

**Positiv / Positive:**

- Die pfadzentrische Trustee-Tabelle hält jetzt das Versprechen
  „who can access this path at all" konsistent mit der Risiko-
  und Erklärungstabelle.
- Share-DACL-Lese-Fehler erscheinen als sichtbare Markierung, nicht
  als unsichtbare Lücke.
- Performance: ein Read pro Share, nicht pro Pfad — bei großen Trees
  ein deutlicher Gewinn.
- API additiv: `build_path_trustees` bleibt; neue
  `build_path_trustees_with_share` und `read_share_overlay`
  ergänzen.

**Negativ / Negative:**

- Die Trustee-Liste pro Pfad ist potenziell länger (NTFS-ACEs +
  Share-ACEs). Das ist gewollt — die Trennung über
  `TrusteeCategory::{Ntfs, Share}` macht die Quelle erkennbar.

**Test-Anforderungen:**

- Es gibt aktuell keinen automatisierten Test für den Scan-Pfad mit
  vorhandener Share-DACL, weil der GUI-Worker eine SMB-Live-Probe
  benötigt. Manueller Smoke-Test über die GUI ist Teil des
  v1.5.0-Release-Checks.

## Schließt / Closes

Review 2026-06-04 Runde 3, Finding 3 (Scan-/HTML-Trustee-Ansicht
liess Share-DACL-Trustees weg).

## Verweise / References

- ADR 0026 — Persistente Scan-Historie (`PathTrustees` als Modell).
- ADR 0031 — `effective_smb_target` für die Server-Wahl im Scan-Pfad.
- ADR 0036 — Einheitliche Principal-Resolution-Pipeline (parallel).
- ADR 0037 — Validierte Wrapper konsequent (parallel).
