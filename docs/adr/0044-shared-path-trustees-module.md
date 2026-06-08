# ADR 0044 — Pfadzentrische Trustees als gemeinsames Modul für GUI und CLI

**Status:** Accepted
**Date:** 2026-06-06

## Context

Stars beantwortet zwei Audit-Fragen pro Pfad:

1. **Identitäts-bezogen:** „Welche effektive Berechtigung hat dieser Benutzer auf diesen Pfad?" — beantwortet durch `EffectivePermission` aus der Permission-Engine.
2. **Pfad-bezogen:** „Wer steht überhaupt auf der ACL dieses Pfads — und auf der Share-DACL des umgebenden Shares?" — beantwortet durch `PathTrustees` mit `Vec<PathTrustee>`.

Die zweite Frage ist *identitätsfrei*: sie ist die rohe Aufzählung aller Trustees pro Pfad, nicht die rechnerische Aggregation für eine konkrete Identität. Sie ist genauso wichtig wie die erste, weil ein Audit-Tool sonst die Frage „wer kann hier eigentlich überhaupt was?" nicht beantworten kann — und das ist die Frage, die Auditoren am häufigsten zuerst stellen.

Bis v1.5.13 wurde diese Liste **nur in der GUI** gebaut. Die Helfer-Funktionen `read_share_overlay`, `build_path_trustees` und `build_path_trustees_with_share` lagen privat in `crates/gui/src/worker.rs`. Die CLI hatte keinen Zugriff darauf und schickte den Exportern (HTML, JSON) immer ein `AnalysisResult` mit leerem `path_trustees`. Konsequenz für CLI-Audits:

- `adpa analyze --output report.json --path X --user alice` → JSON ohne `path_trustees`.
- `adpa scan --output report.json --path X --user alice` → JSON ohne `path_trustees`.
- HTML-Reports aus der CLI: technische Render-Logik für die Trustee-Tabelle war im `HtmlExporter` zwar vorhanden, aber wegen leerem Eingangsfeld wurde sie nie ausgelöst.

Die zweite Audit-Frage war für CLI-Audits damit faktisch *nicht beantwortet* — ein still-falscher Zustand, weil der Bericht *aussah* als wäre er vollständig.

Round-9 Review-Finding 1 hat das als Medium klassifiziert. Die GUI war korrekt, aber die Daten waren in der falschen Schicht. Empfehlung: in eine non-UI-Schicht extrahieren, CLI und GUI teilen das.

## Decision

Die Trustee-Build-Logik wandert in ein neues Modul **`crates/exporter/src/trustees.rs`**. Die Wahl der Crate folgt drei Kriterien:

1. **`exporter` ist die natürliche semantische Heimat.** Trustees sind Reportdaten, keine Engine-Logik. Sie werden in einem Reportformat seriell ausgegeben — und genau das macht `exporter`. Eine eigene Crate `reporting` wäre redundant.
2. **`exporter` hat keine UI-Abhängigkeit.** Damit sind GUI und CLI gleichberechtigte Konsumenten. Weder die GUI muss CLI-Code laden noch umgekehrt.
3. **`exporter` hat keine Engine-Abhängigkeit nach oben.** `exporter` darf in `permission_engine` und `share_scanner` hineingreifen, aber nicht in `cli` oder `gui`. Das passt zur Layering-Richtung des Workspace (ADR 0023 — Layering der Crates).

### Schnittstelle

```rust
pub struct ShareTrusteeOverlay {
    pub trustees: Vec<PathTrustee>,
}

pub fn read_share_overlay(server: &str, share_name: &str) -> ShareTrusteeOverlay;

pub fn build_path_trustees(
    fso: &FileSystemObject,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Vec<PathTrustee>;

pub fn build_path_trustees_with_share(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrustee>;
```

Die beiden Build-Funktionen unterscheiden sich nur darin, ob der Aufrufer den Share-Overlay vorab gelesen hat oder ob die Funktion ihn pro Aufruf neu lesen soll. Der vorab-gelesene Pfad ist die Performance-Variante für Scans (ein DACL-Read pro Share statt pro Pfad).

### Cargo-Auswirkungen

`crates/exporter/Cargo.toml` bekommt zwei neue Dependencies:

```toml
share_scanner = { path = "../share_scanner" }

[target.'cfg(windows)'.dependencies]
ad_resolver = { path = "../ad_resolver" }
```

`ad_resolver` ist `cfg(windows)`-only, weil LSA nur auf Windows existiert. Auf Nicht-Windows-Plattformen bleibt `display_name` einfach `None` — die Build-Funktion funktioniert trotzdem, nur die Lesbarkeits-Spalte fehlt.

### GUI-Anpassung

Die GUI-private Implementierung wird ersatzlos gestrichen. `crates/gui/src/worker.rs` re-exportiert die Symbole:

```rust
pub use exporter::{
    build_path_trustees,
    build_path_trustees_with_share,
    read_share_overlay,
    ShareTrusteeOverlay,
};
```

Damit bleiben alle bestehenden GUI-Aufrufstellen und 11 GUI-Tests unverändert lauffähig. Die GUI-spezifische Display-Formatierung (`trustee_row_for_display`) bleibt in der GUI, weil sie Slint-Render-Typen befüllt.

### CLI-Anpassung

`crates/cli/src/main.rs::run_analyze` ruft die einfache Form:

```rust
let trustees = exporter::build_path_trustees(
    &fso,
    smb_server.as_deref(),
    share_name.as_deref(),
);
```

und legt den Eintrag in `AnalysisResult.path_trustees` ab.

`crates/cli/src/main.rs::run_scan` liest **einmal** vor der Pfad-Schleife:

```rust
#[cfg(windows)]
let scan_share_overlay = match (smb_server, share_name) {
    (Some(server), Some(name)) if !server.is_empty() && !name.is_empty() =>
        Some(exporter::read_share_overlay(server, name)),
    _ => None,
};
```

und übergibt den Overlay an jeden Pfad-Aufruf. Damit ist die Share-DACL-Read-Last konstant pro Scan statt linear pro Pfad — identisches Verhalten wie der GUI-Scan-Pfad seit ADR 0038.

## Consequences

### Positiv

- **Format-Symmetrie erreicht:** HTML- und JSON-Reports aus CLI und GUI haben jetzt dieselbe Datenbasis. Der CHANGELOG-Anspruch von v1.5.13 („HTML und JSON haben die gleichen Audit-Informationen") stimmt mit v1.5.14 jetzt auch für die CLI.
- **Eine Datenquelle, zwei Konsumenten:** ein zukünftiger Bugfix in den Build-Funktionen wirkt automatisch in GUI und CLI. Vorher hätte jeder Fix doppelt erfolgen müssen — und genau das passiert in der Praxis nicht.
- **Architekturkonsistenz:** die Schichten-Richtung des Workspace bleibt intakt (`exporter` → `share_scanner`, `core`, kein Sprung in `cli`/`gui`).
- **Tests sind plattform-unabhängig:** die drei neuen Unit-Tests im Modul (`ntfs_only_yields_all_ntfs_trustees`, `null_dacl_yields_explicit_pseudo_row`, `share_overlay_is_appended_to_ntfs_trustees`) laufen auch auf CI-Linux durch, weil sie keine Windows-API berühren.

### Negativ / Trade-offs

- `crates/exporter` hat jetzt eine Dependency auf `share_scanner` — vorher war es eine reine „Daten-→-Format"-Crate. Die Erweiterung ist konzeptuell gerechtfertigt (Trustees sind Teil des Reports), aber sie dehnt die Verantwortung der Crate leicht aus.
- Aufrufer, die *nur* den Render-Teil von `exporter` wollen, ziehen jetzt `share_scanner` als transitive Abhängigkeit mit. In der Praxis trifft das nur den Workspace selbst — keine externen Konsumenten.
- `cfg(windows)` an zwei Stellen: einmal für `ad_resolver` in Cargo.toml, einmal in `trustees.rs` für die LSA-Auflösung. Das ist die Norm in diesem Workspace.

### Beziehung zu anderen ADRs

- **ADR 0036** (Unified Principal Resolution Pipeline): teilt das Prinzip „eine Datenquelle, von beiden Konsumenten konsumiert".
- **ADR 0038** (Share-Trustees im Scan-Pfad): hat den Share-Overlay-Mechanismus eingeführt — ADR 0044 setzt ihn jetzt CLI-seitig identisch um.
- **ADR 0023** (Workspace-Layering): begründet die Wahl von `exporter` als Heimat.

### Tests

Drei neue Tests in `crates/exporter/src/trustees.rs`:

| Test | Was er garantiert |
|---|---|
| `ntfs_only_yields_all_ntfs_trustees` | Ohne Share-Overlay erscheinen alle NTFS-ACEs in der `Ntfs`-Kategorie, kein `Share`-Eintrag wird konstruiert. |
| `null_dacl_yields_explicit_pseudo_row` | Eine NULL-DACL liefert eine sichtbare „Everyone (NULL DACL)"-Pseudo-Zeile statt eines stillen Skips. |
| `share_overlay_is_appended_to_ntfs_trustees` | Mit Share-Overlay erscheinen NTFS- und Share-Einträge getrennt sichtbar, in der Reihenfolge NTFS → Share. |

Plus 11 bestehende GUI-Tests laufen unverändert weiter (verifizieren, dass der Re-Export funktioniert), plus die Round-8-Folgereview-Tests für `JsonExporter`, `CsvExporter`, `HtmlExporter` aus v1.5.13.
