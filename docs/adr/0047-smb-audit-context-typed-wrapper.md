# ADR 0047 — `SmbAuditContext`: typisierter Wrapper als einzige Quelle für Server/Share-Ableitung

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-06

## Kontext / Context

Stars muss an mehreren Stellen aus einem Pfad und optionalen expliziten Flags ableiten, **welcher SMB-Server** und **welcher Share** für eine Share-DACL-Abfrage gelten. Diese Ableitung wurde bisher mit zwei separaten Helfern getragen:

```rust
// crates/validation/src/path.rs
pub fn parse_unc_components(path: &str) -> Option<(String, String)>;
pub fn effective_smb_target(path: &str, explicit_smb_server: Option<&str>) -> Option<String>;
```

Verschiedene Aufrufstellen kombinieren diese Funktionen jeweils per Hand, um aus Pfad + Server-Flag + Share-Flag die finalen `(server, share)`-Strings zu bilden:

```rust
// CLI: resolve_scan_share_status
let path_components = parse_unc_components(path);
let server = match effective_smb_target(path, smb_server) {
    Some(s) => s,
    None => return NotApplicable,
};
let share = match share_name {
    Some(s) => s.to_owned(),
    None => match path_components {
        Some((_, s)) => s,
        None => return NotApplicable,
    },
};
```

Review-Runde 10 Finding 1 hat aufgedeckt, dass die neue Trustee-Overlay-Erzeugung (`build_path_trustees`, `read_share_overlay`) dieselbe Ableitung **nicht** dupliziert hat:

```rust
// CLI: run_analyze (vorher)
let trustees = exporter::build_path_trustees(
    &fso,
    smb_server.as_deref(),       // <-- nur das explizite Flag,
    share_name.as_deref(),       // <-- KEIN UNC-Fallback
);

// CLI: run_scan (vorher)
#[cfg(windows)]
let scan_share_overlay = match (smb_server.as_deref(), share_name.as_deref()) {
    (Some(server), Some(name)) if !server.is_empty() && !name.is_empty() => {
        Some(exporter::read_share_overlay(server, name))
    }
    _ => None,                    // <-- bei reinem UNC ohne Flags: nichts
};
```

Konsequenz: Ein Aufruf wie

```
adpa scan --path \\fs01\data --user alice --output report.json
```

lieferte die *korrekte* `share_status`-Maske (`resolve_scan_share_status` nutzte den UNC-Fallback), aber die `path_trustees`-Liste enthielt **nur die NTFS-Schicht**. Das war eine stille Daten-Asymmetrie innerhalb desselben Reports — der Auditor sah zwei verschiedene „Wahrheiten" über denselben Pfad.

Drei eigenständige Stellen mit drei eigenständigen Implementierungen derselben Ableitung sind **per se eine Bug-Klasse**: jede Stelle kann unabhängig falsch werden, und Review muss sie alle einzeln verifizieren.

## Entscheidung / Decision

Wir führen einen **typisierten Wrapper** `SmbAuditContext` ein, der zur einzigen Quelle der Wahrheit für die Server/Share-Ableitung wird:

```rust
// crates/validation/src/path.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAuditContext {
    pub server: String,
    pub share: String,
}

impl SmbAuditContext {
    pub fn resolve(
        path: &str,
        explicit_smb_server: Option<&str>,
        explicit_share_name: Option<&str>,
    ) -> Option<Self>;
}
```

### Design-Entscheidungen

1. **Pro Feld: explizit > UNC-Komponente.** Wenn `--smb-server fs02` angegeben ist, gewinnt der explizite Server auch bei einem UNC-Pfad `\\fs01\…`. Begründet in einem Audit-Szenario, wo die Share-DACL auf einem anderen Server liegt als der NTFS-Pfad (z. B. DR-Replikation).
2. **Beide Felder oder gar nichts (`Option<Self>`).** Wenn nur der Server bestimmbar ist (zum Beispiel `--smb-server fs01` mit lokalem Pfad `C:\data` ohne `--share-name`), liefert `resolve` `None`. Begründung: für einen DACL-Lookup braucht man **beides**. Halbe Information führte zu silently-failing-Calls mit leerem Share-Namen.
3. **Leere String-Flags zählen als „nicht gesetzt".** `Some("")` und `Some("   ")` werden wie `None` behandelt. Begründung: CLI-Frontends und GUI-Bindings geben oft `Some("")` statt `None`, wenn ein Feld nicht ausgefüllt wurde. Das war Quelle für falsche Trustee-Lookups in der GUI vor v1.5.14.

### Wo der Wrapper verwendet wird

Mit Round 10 wird `SmbAuditContext::resolve` zur zentralen Stelle für die drei Pfade, die vorher entweder auseinanderdrifteten oder doppelten Code trugen:

| Aufrufstelle | Vorher | Nachher |
|---|---|---|
| `cli::main::run_analyze` (Trustee-Overlay) | nur explizite Flags, kein UNC-Fallback | `SmbAuditContext::resolve(...)` |
| `cli::main::run_scan` (Trustee-Overlay) | nur explizite Flags, kein UNC-Fallback | `SmbAuditContext::resolve(...)` |
| `cli::main::resolve_scan_share_status` | manuelle Kombination `effective_smb_target` + `parse_unc_components` | `SmbAuditContext::resolve(...)` |
| `gui::worker::sweep_one_root` (Trustee-Overlay) | manuelle Kombination | `SmbAuditContext::resolve(...)` |
| `gui::worker::compute_share_mask_for_analyze` | manuelle Kombination | `SmbAuditContext::resolve(...)` |

Damit haben CLI-Analyze, CLI-Scan und GUI-Scan **garantiert** dieselbe Sicht auf den SMB-Kontext. Mask-Berechnung und Trustee-Overlay sind nicht mehr ableitungs-asymmetrisch.

### Wo der Wrapper bewusst NICHT verwendet wird

`effective_smb_target` bleibt für Aufrufer erhalten, die nur den Server brauchen (z. B. `compute_local_group_memberships_for_analyze` für lokale Gruppen — Share-Name irrelevant). Das ist semantisch eine andere Frage und sollte typisiert separat bleiben.

`parse_unc_components` bleibt für Aufrufer erhalten, die explizit nur die Roh-Komponenten des UNC-Pfads brauchen (zum Beispiel in Validierungsfehlermeldungen).

### Tests

Sechs Tests im `validation::path::tests`-Modul decken die Invarianten ab:

| Test | Was er garantiert |
|---|---|
| `smb_audit_context_from_unc_alone` | Reiner UNC ohne Flags → beide Felder aus dem Pfad. **Direktes Round-10-Finding-1-Verhalten.** |
| `smb_audit_context_explicit_flags_override_unc` | Explizite Flags gewinnen pro Feld. |
| `smb_audit_context_local_path_yields_none` | Lokaler Pfad ohne Flags → `None`. Schützt vor dem `C:` als Server-Bug. |
| `smb_audit_context_server_without_share_yields_none` | Halb-Kontext (Server explizit, kein Share) → `None`. Schützt vor `get_share_dacl`-Calls mit leerem Share. |
| `smb_audit_context_mixed_explicit_server_unc_share` | Mischform: Server explizit, Share aus UNC. |
| `smb_audit_context_empty_explicit_flags_are_treated_as_none` | `Some("")` zählt als nicht gesetzt — defensive gegen GUI-Frontends. |

## Konsequenzen / Consequences

### Positiv

- **Bug-Klasse eliminiert.** Drei Stellen, die Server/Share unabhängig ableiteten, sind durch eine geteilte Quelle ersetzt. Jede zukünftige Korrektur an der Ableitung wirkt automatisch überall.
- **Typsystem statt Konvention.** `SmbAuditContext` ist als Struct mit `server: String, share: String` so klar wie möglich. Wer es hat, weiß, dass **beide** Felder valide sind.
- **Datensymmetrie zwischen Mask und Trustees.** Ein und derselbe Report sieht nicht mehr zwei verschiedene Server/Share-Wahrheiten in der Mask-Berechnung und der Trustee-Liste.
- **Test-Abdeckung erweitert.** Sechs neue Unit-Tests im `validation`-Crate sichern die Invarianten plattform-unabhängig.

### Negativ / Trade-offs

- `Option<SmbAuditContext>` muss vom Aufrufer entpackt werden. Bisher hätte ein Halbkontext (nur Server) einen DACL-Call mit leerem Share-Namen ausgelöst und intern gescheitert. Jetzt scheitert die Ableitung früher und sauberer — aber Aufrufer, die vorher implizit mit dem Halbkontext gerechnet haben, müssen jetzt explizit den `None`-Fall behandeln. Im aktuellen Workspace ist das auf vier Aufrufstellen begrenzt und überall korrekt umgesetzt.
- Eine zusätzliche Typ-Definition in der Public-API von `validation`. Kostet etwas mehr Doku-Aufmerksamkeit, ist aber semantisch wertvoll.

### Beziehung zu anderen ADRs

- **ADR 0043** (AccessContext mit SMB-Hints): `AccessContext::for_path_with_smb` bekommt die SMB-Hinweise vom Aufrufer. Wer `SmbAuditContext::resolve` benutzt, übergibt direkt `(server, share)` weiter — kein Doppel-Lookup nötig.
- **ADR 0044** (`exporter::trustees` als shared module): das Modul nimmt `Option<&str>, Option<&str>` für die SMB-Hints. Aufrufer in CLI und GUI füllen diese Felder jetzt aus `SmbAuditContext`.
