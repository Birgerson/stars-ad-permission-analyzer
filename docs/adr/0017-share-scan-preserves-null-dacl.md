# ADR 0017 — Share-Scan erhält die NULL-DACL-Semantik

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

`get_share_dacl` unterscheidet seit ADR 0010 korrekt zwischen
`ShareDacl::NullDacl` (keine Zugriffseinschränkung — Vollzugriff für
alle) und `ShareDacl::Acl(vec![])` (vorhandene leere DACL — kein
Zugriff). Die Unterscheidung ist für Audits wesentlich:

- NULL DACL ist häufig ein Konfigurationsfehler (Vollzugriff für alle
  über SMB) — muss in der Reportierung sichtbar sein.
- Eine leere DACL ist hingegen ein bewusstes „kein Zugriff".

Der kombinierte Einstiegspunkt `scan_shares` rief jedoch
`get_share_permissions`, der `ShareDacl::NullDacl` zu einer leeren
`Vec<SharePermission>` glättet — danach war im flachen
`ShareScanResult.permissions`-Feld nicht mehr unterscheidbar, ob eine
Freigabe keine Einschränkung hat oder effektiv keinen Zugriff zulässt.

Siehe Review-Befund 7.

## Entscheidung / Decision

1. **`ShareScanResult` trägt zusätzlich ein strukturiertes Feld**

   ```rust
   pub struct ShareScanResult {
       pub shares: Vec<Share>,
       pub permissions: Vec<SharePermission>,
       pub errors: Vec<ShareScanError>,
       pub share_dacls: Vec<(String, ShareDacl)>,
   }
   ```

   `share_dacls` enthält für jede erfolgreich gelesene Freigabe ihren
   `ShareDacl`-Status. Für Audits ist `share_dacls` die maßgebliche
   Quelle; `permissions` bleibt als flach aggregierte Konvenienz für
   Aufrufer erhalten, die keine pro-Share-Auflösung brauchen.

2. **`scan_shares` ruft direkt `get_share_dacl`** statt
   `get_share_permissions`. Für jeden Share:

   - `Ok(dacl)` → `(name, dacl)` wandert in `share_dacls`; bei
     `Acl(perms)` wird `perms` zusätzlich in `permissions` flach
     aggregiert.
   - `Err(e)` → wie bisher in `errors`.

   `null_dacl_shares` wird im Abschluss-Log mitgezählt — Operatoren
   sehen so direkt, wie viele Freigaben unrestricted sind.

3. **`ShareDacl` derived `Clone`**, damit der Wert sowohl in
   `share_dacls` gespeichert als auch zum flachen Aggregieren genutzt
   werden kann.

4. **`get_share_permissions` bleibt unverändert** als bequemer Pfad
   für Aufrufer, denen die NULL/empty-Unterscheidung egal ist. Sein
   Docstring weist seit ADR 0010 schon auf `get_share_dacl` für den
   strikten Fall hin.

## Begründung / Rationale

- **Minimal invasiv:** Bestehende Aufrufer von `ShareScanResult`
  (intern: Tests; extern: keine produktiven) sehen das neue Feld
  zusätzlich — kein Bruch.
- **Audit-Korrektheit hat Vorrang** (AGENTS.md Grundregel 1) — eine
  Freigabe mit Vollzugriff für alle darf nicht in der gleichen Form
  wie „kein Zugriff" persistiert/exportiert werden.
- **Konsistenz mit dem FSO-Pfad:** Auf NTFS-Seite trägt
  `FileSystemObject.null_dacl` bereits die Unterscheidung; die
  Share-Seite zieht jetzt nach.

## Konsequenzen / Consequences

- 3 neue Tests in `share_scanner::scanner::tests`:
  - `scan_shares_records_dacl_status_for_every_successful_share`
  - `permissions_equals_flattened_acl_entries_from_share_dacls`
  - `null_dacl_distinguishable_from_empty_acl_in_share_dacls`
    (synthetischer Konstruktions-Test, der die strukturelle
    Unterscheidung beweist und beide Fälle durch
    `effective_share_mask` schickt: `NullDacl → None`,
    `Acl([]) → Some(0)`).
- Kein Schemawechsel — `share_dacls` lebt nur im In-Memory-Result.
  Wenn später Persistenz pro-Share gewünscht ist, kann darauf
  aufgesetzt werden.
- ADR 0010 bleibt gültig; ADR 0017 erweitert die NULL/empty-
  Unterscheidung auf den kombinierten Scan-Pfad.
